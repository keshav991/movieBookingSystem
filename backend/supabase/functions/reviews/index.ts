// Edge Function: reviews — only verified bookers can post; supports GET by movie, POST, DELETE own review

import { serve } from "https://deno.land/std@0.208.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

serve(async (req: Request) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
      },
    });
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
  const url = new URL(req.url);
  const pathParts = url.pathname.split("/").filter(Boolean);

  const token = req.headers.get("Authorization")?.replace("Bearer ", "");

  try {
    // GET /reviews?movie_id=  — Public: fetch visible reviews for a movie
    if (req.method === "GET" && pathParts.length === 1) {
      const movie_id = url.searchParams.get("movie_id");
      if (!movie_id) return json({ error: "movie_id query param is required" }, 400);

      const { data, error } = await supabase
        .from("reviews")
        .select("id, rating, review_text, created_at, profiles(name, avatar_url)")
        .eq("movie_id", movie_id)
        .eq("is_visible", true)
        .order("created_at", { ascending: false });

      if (error) throw error;
      return json(data);
    }

    // All routes below require authentication
    if (!token) return json({ error: "Unauthorized" }, 401);
    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user) return json({ error: "Unauthorized" }, 401);

    // POST /reviews  — Authenticated: post a review (must have a confirmed booking for that movie)
    if (req.method === "POST" && pathParts.length === 1) {
      const { movie_id, booking_id, rating, review_text } = await req.json() as {
        movie_id: string;
        booking_id: string;
        rating: number;
        review_text?: string;
      };

      if (!movie_id || !booking_id || !rating) {
        return json({ error: "movie_id, booking_id, and rating are required" }, 400);
      }

      if (rating < 1 || rating > 10) {
        return json({ error: "Rating must be between 1 and 10" }, 400);
      }

      // Verify the booking belongs to this user, is confirmed, and is for this movie
      const { data: booking, error: bookingErr } = await supabase
        .from("bookings")
        .select("id, show_id, shows(movie_id)")
        .eq("id", booking_id)
        .eq("user_id", user.id)
        .eq("status", "confirmed")
        .single();

      if (bookingErr || !booking) {
        return json({ error: "No confirmed booking found for this user" }, 403);
      }

      const bookedMovieId = (booking.shows as unknown as { movie_id: string } | null)?.movie_id;
      if (bookedMovieId !== movie_id) {
        return json({ error: "Booking does not match the movie" }, 403);
      }

      const { data: review, error: reviewErr } = await supabase
        .from("reviews")
        .insert({
          user_id: user.id,
          movie_id,
          booking_id,
          rating,
          review_text: review_text ?? null,
        })
        .select()
        .single();

      if (reviewErr) {
        if (reviewErr.code === "23505") {
          return json({ error: "You have already reviewed this movie" }, 409);
        }
        throw reviewErr;
      }

      // Recalculate and update avg_rating + total_ratings on the movies table
      const { data: allRatings } = await supabase
        .from("reviews")
        .select("rating")
        .eq("movie_id", movie_id)
        .eq("is_visible", true);

      if (allRatings && allRatings.length > 0) {
        const avg = allRatings.reduce((sum, r) => sum + r.rating, 0) / allRatings.length;
        await supabase
          .from("movies")
          .update({
            avg_rating: Math.round(avg * 10) / 10,
            total_ratings: allRatings.length,
          })
          .eq("id", movie_id);
      }

      return json(review, 201);
    }

    // DELETE /reviews/:id  — Authenticated: delete own review and recalculate avg_rating
    if (req.method === "DELETE" && pathParts.length === 2) {
      const reviewId = pathParts[1];

      const { data: existing, error: fetchErr } = await supabase
        .from("reviews")
        .select("id, movie_id, user_id")
        .eq("id", reviewId)
        .single();

      if (fetchErr || !existing) return json({ error: "Review not found" }, 404);
      if (existing.user_id !== user.id) return json({ error: "Forbidden" }, 403);

      const { error: deleteErr } = await supabase
        .from("reviews")
        .delete()
        .eq("id", reviewId);

      if (deleteErr) throw deleteErr;

      const { data: remaining } = await supabase
        .from("reviews")
        .select("rating")
        .eq("movie_id", existing.movie_id)
        .eq("is_visible", true);

      const newAvg = remaining && remaining.length > 0
        ? Math.round((remaining.reduce((s, r) => s + r.rating, 0) / remaining.length) * 10) / 10
        : 0;

      await supabase
        .from("movies")
        .update({ avg_rating: newAvg, total_ratings: remaining?.length ?? 0 })
        .eq("id", existing.movie_id);

      return json({ success: true });
    }

    return json({ error: "Not found" }, 404);
  } catch (err) {
    return json({ error: (err as Error).message }, 500);
  }
});

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" },
  });
}
